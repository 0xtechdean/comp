import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { auth } from '../../auth/auth.server';

export interface CallbackStateOwner {
  userId: string;
  organizationId: string;
}

export interface SessionMismatch {
  reason: string;
  message: string;
}

/**
 * Shared support for provider callbacks that arrive as a browser redirect.
 *
 * Callback endpoints cannot sit behind HybridAuthGuard — the provider redirects
 * the user's browser to them, and a guard would turn every failure into an
 * opaque 401. Instead they validate the server-issued `state` and then confirm
 * the caller's session belongs to whoever started the flow, so a leaked state
 * value alone cannot bind an integration to someone else's organization.
 *
 * Extracted so the OAuth and GitHub App callbacks cannot drift apart: a
 * weakening of this check in one flow would otherwise go unnoticed in the other.
 */
@Injectable()
export class OAuthCallbackSupportService {
  /**
   * Verify the caller's better-auth session matches the user (and active org,
   * when present) recorded on the flow state. Returns a reason on mismatch, or
   * null when it is safe to continue.
   */
  async checkSessionMatchesState(
    req: Request,
    state: CallbackStateOwner,
  ): Promise<SessionMismatch | null> {
    const headers = new Headers();
    const authHeader = req.headers['authorization'];
    if (typeof authHeader === 'string' && authHeader) {
      headers.set('authorization', authHeader);
    }
    const cookieHeader = req.headers['cookie'];
    if (typeof cookieHeader === 'string' && cookieHeader) {
      headers.set('cookie', cookieHeader);
    }

    const noSession: SessionMismatch = {
      reason: 'no_session',
      message:
        'No active session. Please sign in and restart the integration flow.',
    };

    if (!authHeader && !cookieHeader) return noSession;

    const session = await auth.api.getSession({ headers });
    const sessionUserId = session?.user?.id;
    if (!sessionUserId) return noSession;

    if (sessionUserId !== state.userId) {
      return {
        reason: 'user_mismatch',
        message:
          'This flow can only be completed by the user who initiated it.',
      };
    }

    const sessionData = session.session as Record<string, unknown> | undefined;
    const activeOrgRaw = sessionData?.activeOrganizationId;
    const activeOrganizationId =
      typeof activeOrgRaw === 'string' ? activeOrgRaw : undefined;

    if (activeOrganizationId && activeOrganizationId !== state.organizationId) {
      return {
        reason: 'organization_mismatch',
        message: 'Flow organization does not match the active session.',
      };
    }

    return null;
  }

  /**
   * Build the URL to redirect the browser back to, falling back to the org's
   * integrations page when the flow did not record one.
   */
  buildRedirectUrl(
    baseUrl: string | null | undefined,
    params: Record<string, string>,
    organizationId?: string,
  ): string {
    let targetUrl: string;
    if (baseUrl) {
      targetUrl = baseUrl;
    } else {
      targetUrl = `${process.env.APP_URL || 'http://localhost:3000'}`;
      targetUrl += organizationId
        ? `/${organizationId}/integrations`
        : '/integrations';
    }

    const url = new URL(targetUrl);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
    return url.toString();
  }
}
