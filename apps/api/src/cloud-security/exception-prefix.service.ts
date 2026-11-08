import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { db } from '@db';
import { logCloudSecurityActivity } from './cloud-security-audit';
import { MIN_PREFIX_LENGTH } from './dto/mark-prefix-exception.dto';
import { MIN_EXCEPTION_REASON_LENGTH } from './exception.service';

/** A class exception must be re-reviewed at least yearly. */
export const MAX_PREFIX_EXCEPTION_DAYS = 366;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface MarkPrefixExceptionInput {
  organizationId: string;
  connectionId: string;
  checkIdPrefix: string;
  resourceIdPrefix: string;
  /** Acting user (see MarkExceptionInput in exception.service.ts). */
  userId: string;
  reason: string;
  reviewedBy?: string | null;
  expiresAt: Date | null;
  callerLabel?: string;
}

/**
 * Class exceptions: one reviewed, expiring exception for every finding on a
 * connection whose check id and resource id start with the given prefixes.
 * Matching lives in finding-exceptions.ts with the exact exceptions, so every
 * surface honours both the same way.
 */
@Injectable()
export class CloudPrefixExceptionService {
  async markPrefixException(
    input: MarkPrefixExceptionInput,
  ): Promise<{ id: string }> {
    const checkIdPrefix = input.checkIdPrefix.trim();
    const resourceIdPrefix = input.resourceIdPrefix.trim();
    const reason = input.reason.trim();

    if (reason.length < MIN_EXCEPTION_REASON_LENGTH) {
      throw new BadRequestException(
        `Exception reason must be at least ${MIN_EXCEPTION_REASON_LENGTH} characters.`,
      );
    }
    if (
      checkIdPrefix.length < MIN_PREFIX_LENGTH ||
      resourceIdPrefix.length < MIN_PREFIX_LENGTH
    ) {
      throw new BadRequestException(
        `Both prefixes must be at least ${MIN_PREFIX_LENGTH} characters, so the exception cannot match everything.`,
      );
    }
    this.assertExpiry(input.expiresAt);

    const connection = await db.integrationConnection.findFirst({
      where: { id: input.connectionId, organizationId: input.organizationId },
      select: { id: true },
    });
    if (!connection) {
      throw new ForbiddenException(
        'Connection not found, or it does not belong to your organization.',
      );
    }

    const fields = {
      reason,
      reviewedBy: input.reviewedBy ?? null,
      expiresAt: input.expiresAt,
      markedById: input.userId,
      match: 'prefix' as const,
    };
    const upserted = await db.findingException.upsert({
      where: {
        organizationId_connectionId_checkId_resourceId: {
          organizationId: input.organizationId,
          connectionId: input.connectionId,
          checkId: checkIdPrefix,
          resourceId: resourceIdPrefix,
        },
      },
      create: {
        organizationId: input.organizationId,
        connectionId: input.connectionId,
        checkId: checkIdPrefix,
        resourceId: resourceIdPrefix,
        ...fields,
      },
      update: {
        ...fields,
        revokedAt: null,
        revokedById: null,
        markedAt: new Date(),
      },
    });

    const reasonPreview = `${reason.slice(0, 80)}${reason.length > 80 ? '…' : ''}`;
    const summary = `Marked every finding matching ${checkIdPrefix}*:${resourceIdPrefix}* as an exception — ${reasonPreview}`;
    await logCloudSecurityActivity({
      organizationId: input.organizationId,
      userId: input.userId,
      connectionId: input.connectionId,
      action: 'exception_marked',
      description: input.callerLabel
        ? `[${input.callerLabel}] ${summary}`
        : summary,
      metadata: {
        exceptionId: upserted.id,
        match: 'prefix',
        checkIdPrefix,
        resourceIdPrefix,
        expiresAt: input.expiresAt?.toISOString() ?? null,
        callerLabel: input.callerLabel ?? null,
      },
    });

    return { id: upserted.id };
  }

  private assertExpiry(expiresAt: Date | null): void {
    if (!expiresAt) {
      throw new BadRequestException(
        'A class exception needs an expiry date, so it is re-reviewed.',
      );
    }
    const now = Date.now();
    if (expiresAt.getTime() <= now) {
      throw new BadRequestException(
        'Exception expiration date must be in the future.',
      );
    }
    if (expiresAt.getTime() > now + MAX_PREFIX_EXCEPTION_DAYS * DAY_MS) {
      throw new BadRequestException(
        `A class exception may run at most ${MAX_PREFIX_EXCEPTION_DAYS} days.`,
      );
    }
  }
}
