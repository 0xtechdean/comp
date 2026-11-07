import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsDateString,
  IsOptional,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

/** Shortest prefixes accepted, so a class exception cannot match everything. */
export const MIN_PREFIX_LENGTH = 8;

export class MarkPrefixExceptionDto {
  @ApiProperty({
    description: 'Cloud connection whose findings the exception covers.',
    example: 'icn_abc123def456',
  })
  @IsString()
  connectionId!: string;

  @ApiProperty({
    description: `Every finding whose check id starts with this is covered (both prefixes must match). At least ${MIN_PREFIX_LENGTH} characters.`,
    example: 'secrets-no-rotation-cloud/stacks/dep_',
  })
  @IsString()
  @MinLength(MIN_PREFIX_LENGTH)
  checkIdPrefix!: string;

  @ApiProperty({
    description: `Every finding whose resource id starts with this is covered (both prefixes must match). At least ${MIN_PREFIX_LENGTH} characters.`,
    example:
      'arn:aws:secretsmanager:eu-central-1:123456789012:secret:cloud/stacks/dep_',
  })
  @IsString()
  @MinLength(MIN_PREFIX_LENGTH)
  resourceIdPrefix!: string;

  @ApiProperty({
    description:
      'Why this class of findings is accepted. Minimum 20 non-whitespace characters.',
    example:
      'One secret bundle per deployed stack, written once and read by External Secrets; encrypted under a restricted CMK.',
  })
  @IsString()
  @MinLength(20, { message: 'Reason must be at least 20 characters.' })
  @Matches(/(?:\S.*?){20}/s, {
    message: 'Reason must contain at least 20 non-whitespace characters.',
  })
  reason!: string;

  @ApiPropertyOptional({
    description: 'Free-text reviewer or approval reference.',
    example: 'Approved by CTO 2026-11-07',
  })
  @IsOptional()
  @IsString()
  reviewedBy?: string;

  @ApiProperty({
    description:
      'ISO date when the class exception expires. Required, at most one year ahead, so it is re-reviewed.',
    example: '2027-10-31',
  })
  @IsDateString()
  expiresAt!: string;
}
