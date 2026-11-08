-- A FindingException can cover a class of findings by prefix (checkId and
-- resourceId both match as prefixes) instead of one exact finding. Existing rows
-- keep their meaning through the default.

-- CreateEnum
CREATE TYPE "FindingExceptionMatch" AS ENUM ('exact', 'prefix');

-- AlterTable
ALTER TABLE "FindingException" ADD COLUMN "match" "FindingExceptionMatch" NOT NULL DEFAULT 'exact';
