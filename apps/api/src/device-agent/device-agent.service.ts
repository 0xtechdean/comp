import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import {
  S3Client,
  GetObjectCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@/app/s3';
import { Readable } from 'stream';

const S3_ENV = process.env.DEVICE_AGENT_S3_ENV || 'production';
const S3_UPDATES_PREFIX = `device-agent/${S3_ENV}/updates`;

/**
 * Installer downloads resolve to the `latest-*` aliases the release pipeline
 * rewrites on every publish, under the same `device-agent/<env>/` prefix the
 * updates feed already uses.
 *
 * These previously pointed at a hardcoded, version-stamped filename
 * ("Comp AI Agent-1.0.0-arm64.dmg") sitting at the bucket root. Both parts
 * were wrong: nothing publishes to the root, and pinning a version means the
 * download serves a stale build — or 404s — the moment a new agent ships.
 */
const INSTALLER_TARGETS = {
  mac: {
    key: `device-agent/${S3_ENV}/macos/latest-arm64.dmg`,
    filename: 'CompAI-Device-Agent-arm64.dmg',
    contentType: 'application/x-apple-diskimage',
    label: 'macOS',
  },
  windows: {
    key: `device-agent/${S3_ENV}/windows/latest-setup.exe`,
    filename: 'CompAI-Device-Agent-setup.exe',
    contentType: 'application/octet-stream',
    label: 'Windows',
  },
} as const;

type InstallerPlatform = keyof typeof INSTALLER_TARGETS;

const ALLOWED_EXTENSIONS = new Set([
  '.yml',
  '.zip',
  '.exe',
  '.blockmap',
  '.AppImage',
  '.dmg',
]);

const CONTENT_TYPES: Record<string, string> = {
  '.yml': 'text/yaml',
  '.zip': 'application/zip',
  '.exe': 'application/octet-stream',
  '.blockmap': 'application/octet-stream',
  '.AppImage': 'application/octet-stream',
  '.dmg': 'application/x-apple-diskimage',
};

/**
 * Binaries are presigned + redirected so the client downloads directly from
 * S3, bypassing proxy/function timeouts. Manifests are tiny enough to stream.
 */
const REDIRECT_EXTENSIONS = new Set([
  '.zip',
  '.exe',
  '.blockmap',
  '.AppImage',
  '.dmg',
]);

const PRESIGNED_URL_TTL_SECONDS = 60 * 60; // 1 hour

function getExtension(filename: string): string {
  if (filename.endsWith('.AppImage')) return '.AppImage';
  const dotIndex = filename.lastIndexOf('.');
  return dotIndex >= 0 ? filename.slice(dotIndex) : '';
}

function isValidFilename(filename: string): boolean {
  if (
    filename.includes('..') ||
    filename.includes('/') ||
    filename.includes('\\')
  ) {
    return false;
  }
  return ALLOWED_EXTENSIONS.has(getExtension(filename));
}

@Injectable()
export class DeviceAgentService {
  private readonly logger = new Logger(DeviceAgentService.name);
  private s3Client: S3Client;
  private fleetBucketName: string;

  constructor() {
    this.fleetBucketName =
      process.env.FLEET_AGENT_BUCKET_NAME || process.env.APP_AWS_BUCKET_NAME!;
    this.s3Client = new S3Client({
      region: process.env.APP_AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.APP_AWS_ACCESS_KEY_ID!,
        secretAccessKey: process.env.APP_AWS_SECRET_ACCESS_KEY!,
      },
    });
  }

  private async downloadInstaller(platform: InstallerPlatform): Promise<{
    stream: Readable;
    filename: string;
    contentType: string;
  }> {
    const { key, filename, contentType, label } = INSTALLER_TARGETS[platform];

    try {
      this.logger.log(`Downloading ${label} agent from S3: ${key}`);

      const s3Response = await this.s3Client.send(
        new GetObjectCommand({ Bucket: this.fleetBucketName, Key: key }),
      );

      if (!s3Response.Body) {
        throw new NotFoundException(`${label} agent file not found in S3`);
      }

      this.logger.log(`Successfully retrieved ${label} agent: ${filename}`);

      return {
        stream: s3Response.Body as Readable,
        filename,
        contentType,
      };
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      this.logger.error(`Failed to download ${label} agent from S3:`, error);
      const s3Error = error as { name?: string };
      if (s3Error.name === 'NoSuchKey' || s3Error.name === 'NotFound') {
        throw new NotFoundException(`${label} agent file not found`);
      }
      throw new InternalServerErrorException(
        `Failed to download ${label} agent. The agent file may not be available in this environment.`,
      );
    }
  }

  async downloadMacAgent(): Promise<{
    stream: Readable;
    filename: string;
    contentType: string;
  }> {
    return this.downloadInstaller('mac');
  }

  async downloadWindowsAgent(): Promise<{
    stream: Readable;
    filename: string;
    contentType: string;
  }> {
    return this.downloadInstaller('windows');
  }

  async getUpdateFile({
    filename,
  }: {
    filename: string;
  }): Promise<UpdateFileResult> {
    if (!isValidFilename(filename)) {
      throw new NotFoundException('Not found');
    }

    const key = `${S3_UPDATES_PREFIX}/${filename}`;
    const ext = getExtension(filename);

    if (REDIRECT_EXTENSIONS.has(ext)) {
      return { kind: 'redirect', url: await this.signUpdateUrl(key, 'GET') };
    }

    const contentType = CONTENT_TYPES[ext] || 'application/octet-stream';

    try {
      const command = new GetObjectCommand({
        Bucket: this.fleetBucketName,
        Key: key,
      });
      const s3Response = await this.s3Client.send(command);

      if (!s3Response.Body) {
        throw new NotFoundException('Not found');
      }

      return {
        kind: 'stream',
        stream: s3Response.Body as Readable,
        contentType,
        contentLength:
          typeof s3Response.ContentLength === 'number'
            ? s3Response.ContentLength
            : undefined,
      };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      const s3Error = error as { name?: string };
      if (s3Error.name === 'NoSuchKey') {
        throw new NotFoundException('Not found');
      }
      this.logger.error('Error serving update file:', { key, error });
      throw new InternalServerErrorException('Internal server error');
    }
  }

  async headUpdateFile({
    filename,
  }: {
    filename: string;
  }): Promise<HeadUpdateFileResult> {
    if (!isValidFilename(filename)) {
      throw new NotFoundException('Not found');
    }

    const key = `${S3_UPDATES_PREFIX}/${filename}`;
    const ext = getExtension(filename);

    if (REDIRECT_EXTENSIONS.has(ext)) {
      // S3 signs each HTTP method separately — a GET-signed URL is rejected
      // for HEAD with SignatureDoesNotMatch.
      return { kind: 'redirect', url: await this.signUpdateUrl(key, 'HEAD') };
    }

    const contentType = CONTENT_TYPES[ext] || 'application/octet-stream';

    try {
      const command = new HeadObjectCommand({
        Bucket: this.fleetBucketName,
        Key: key,
      });
      const s3Response = await this.s3Client.send(command);

      return {
        kind: 'stream',
        contentType,
        contentLength:
          typeof s3Response.ContentLength === 'number'
            ? s3Response.ContentLength
            : undefined,
      };
    } catch {
      throw new NotFoundException('Not found');
    }
  }

  private async signUpdateUrl(
    key: string,
    method: 'GET' | 'HEAD',
  ): Promise<string> {
    const command =
      method === 'HEAD'
        ? new HeadObjectCommand({
            Bucket: this.fleetBucketName,
            Key: key,
          })
        : new GetObjectCommand({
            Bucket: this.fleetBucketName,
            Key: key,
          });
    return getSignedUrl(this.s3Client, command, {
      expiresIn: PRESIGNED_URL_TTL_SECONDS,
    });
  }
}

export type UpdateFileResult =
  | {
      kind: 'stream';
      stream: Readable;
      contentType: string;
      contentLength?: number;
    }
  | { kind: 'redirect'; url: string };

export type HeadUpdateFileResult =
  | { kind: 'stream'; contentType: string; contentLength?: number }
  | { kind: 'redirect'; url: string };
