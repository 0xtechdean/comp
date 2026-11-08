import {
  Body,
  Controller,
  HttpException,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { HybridAuthGuard } from '../auth/hybrid-auth.guard';
import { PermissionGuard } from '../auth/permission.guard';
import { RequirePermission } from '../auth/require-permission.decorator';
import { OrganizationId } from '../auth/auth-context.decorator';
import { ActingUserResolver } from '../auth/acting-user.service';
import type { AuthenticatedRequest } from '../auth/types';
import { MarkPrefixExceptionDto } from './dto/mark-prefix-exception.dto';
import { CloudPrefixExceptionService } from './exception-prefix.service';
import { parseExceptionExpiry } from './exception-expiry.utils';

/**
 * Class (prefix) exceptions. Kept apart from CloudSecurityController, which is
 * already far over the file-size limit; same path prefix, same auth model.
 * Revoking uses the existing DELETE /v1/cloud-security/exceptions/:exceptionId.
 */
@Controller({ path: 'cloud-security', version: '1' })
export class CloudSecurityExceptionsController {
  constructor(
    private readonly prefixExceptions: CloudPrefixExceptionService,
    private readonly actingUser: ActingUserResolver,
  ) {}

  @Post('exceptions/prefix')
  @UseGuards(HybridAuthGuard, PermissionGuard)
  @RequirePermission('integration', 'update')
  @ApiOperation({
    summary: 'Except a class of cloud findings by prefix',
    description:
      'Accepts every finding on one connection whose check id and resource id start with the given prefixes, such as a secret created per stack. Needs an expiry within a year.',
  })
  @ApiBody({ type: MarkPrefixExceptionDto })
  async markPrefixException(
    @Body() body: MarkPrefixExceptionDto,
    @OrganizationId() organizationId: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const acting = await this.actingUser.resolve(req, organizationId);
    if (!acting.userId) {
      throw new HttpException(
        'Cannot attribute this action — your organization must have at least one user with the "owner" role.',
        HttpStatus.BAD_REQUEST,
      );
    }
    const result = await this.prefixExceptions.markPrefixException({
      organizationId,
      connectionId: body.connectionId,
      checkIdPrefix: body.checkIdPrefix,
      resourceIdPrefix: body.resourceIdPrefix,
      userId: acting.userId,
      reason: body.reason,
      reviewedBy: body.reviewedBy ?? null,
      expiresAt: parseExceptionExpiry(body.expiresAt),
      callerLabel: acting.callerLabel,
    });
    return { data: result };
  }
}
