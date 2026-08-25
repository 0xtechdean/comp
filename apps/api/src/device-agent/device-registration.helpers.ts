import { randomUUID } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { db } from '@db';
import { RegisterDeviceDto } from './dto/register-device.dto';

const logger = new Logger('DeviceRegistration');

interface MemberRef {
  id: string;
}

function buildUpdateData(dto: RegisterDeviceDto) {
  return {
    name: dto.name,
    platform: dto.platform,
    osVersion: dto.osVersion,
    hardwareModel: dto.hardwareModel,
    agentVersion: dto.agentVersion,
    // The endpoint agent is the managing source once it registers a device.
    // When it adopts a row previously created by an integration import (matched
    // here by serial for the same member), re-stamp it as an agent device.
    // Otherwise the row stays source='integration', the People tab skips it
    // (it only rolls up agent devices) and a compliant device reads "Missing"
    // there while still showing in the Device tab.
    source: 'agent' as const,
  };
}

export async function registerWithSerial({
  member,
  dto,
}: {
  member: MemberRef;
  dto: RegisterDeviceDto;
}) {
  const existing = await db.device.findUnique({
    where: {
      serialNumber_organizationId: {
        serialNumber: dto.serialNumber!,
        organizationId: dto.organizationId,
      },
    },
    select: { id: true, memberId: true },
  });

  if (existing && existing.memberId !== member.id) {
    // Same physical device, different member. The row is NOT reassigned: doing
    // so would let anyone re-register a colleague's machine under their own
    // login and inherit its compliance history. Instead a synthetic serial is
    // minted so both rows can coexist under the per-org serial unique
    // constraint.
    //
    // The cost is that the two rows look like an unexplained duplicate, and the
    // older one goes stale forever because no agent reports to it any more.
    // Logging the collision makes the cause recoverable — usually one human
    // holding two member identities, which is the thing actually worth fixing.
    logger.warn(
      `Device serial collision: serial=${dto.serialNumber} host=${dto.hostname} ` +
        `is registered to member=${existing.memberId} but was re-registered by ` +
        `member=${member.id} (org=${dto.organizationId}). Creating a separate ` +
        `record with a fallback serial. If these are the same person, ` +
        `consolidate the member identities — device ${existing.id} will go ` +
        `stale but still appear in the device register.`,
    );
    return handleFallbackSerial({ member, dto });
  }

  const updateData = buildUpdateData(dto);

  if (existing) {
    return db.device.update({
      where: { id: existing.id },
      data: { ...updateData, hostname: dto.hostname },
    });
  }

  // Adopt any prior serial-less registration for the same physical device
  // before creating a new row. The agent's serial extraction can return
  // undefined on a cold boot (e.g. macOS `system_profiler` cache not yet
  // built) and a real value on a subsequent boot — without this, the second
  // registration creates a duplicate while the first row stays orphaned and
  // never receives another check-in (frozen at its old compliance state).
  const orphan = await db.device.findFirst({
    where: {
      hostname: dto.hostname,
      memberId: member.id,
      organizationId: dto.organizationId,
      serialNumber: null,
    },
    select: { id: true },
  });

  if (orphan) {
    return db.device.update({
      where: { id: orphan.id },
      data: {
        ...updateData,
        hostname: dto.hostname,
        serialNumber: dto.serialNumber!,
      },
    });
  }

  return db.device.create({
    data: {
      ...updateData,
      hostname: dto.hostname,
      serialNumber: dto.serialNumber!,
      memberId: member.id,
      organizationId: dto.organizationId,
    },
  });
}

async function handleFallbackSerial({
  member,
  dto,
}: {
  member: MemberRef;
  dto: RegisterDeviceDto;
}) {
  const fallback = await db.device.findFirst({
    where: {
      hostname: dto.hostname,
      memberId: member.id,
      organizationId: dto.organizationId,
      serialNumber: { startsWith: `fallback:${dto.serialNumber}:` },
    },
  });

  const updateData = buildUpdateData(dto);

  if (fallback) {
    return db.device.update({
      where: { id: fallback.id },
      data: updateData,
    });
  }

  const fallbackSerial = `fallback:${dto.serialNumber}:${randomUUID()}`;

  logger.warn(
    `Creating duplicate device record for host=${dto.hostname} under ` +
      `member=${member.id} with synthetic serial ${fallbackSerial}. The ` +
      `hardware serial ${dto.serialNumber} belongs to another member's record.`,
  );

  return db.device.create({
    data: {
      ...updateData,
      hostname: dto.hostname,
      serialNumber: fallbackSerial,
      memberId: member.id,
      organizationId: dto.organizationId,
    },
  });
}

export async function registerWithoutSerial({
  member,
  dto,
}: {
  member: MemberRef;
  dto: RegisterDeviceDto;
}) {
  const existing = await db.device.findFirst({
    where: {
      hostname: dto.hostname,
      memberId: member.id,
      organizationId: dto.organizationId,
      serialNumber: null,
    },
  });

  const updateData = buildUpdateData(dto);

  if (existing) {
    return db.device.update({
      where: { id: existing.id },
      data: updateData,
    });
  }

  return db.device.create({
    data: {
      ...updateData,
      hostname: dto.hostname,
      serialNumber: null,
      memberId: member.id,
      organizationId: dto.organizationId,
    },
  });
}
