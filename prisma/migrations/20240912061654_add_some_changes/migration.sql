/*
  Warnings:

  - The `gender` column on the `User` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- CreateEnum
CREATE TYPE "Gender" AS ENUM ('male', 'female');

-- AlterTable
ALTER TABLE "User" ALTER COLUMN "birthdate" DROP NOT NULL,
DROP COLUMN "gender",
ADD COLUMN     "gender" "Gender",
ALTER COLUMN "location" DROP NOT NULL,
ALTER COLUMN "password" DROP NOT NULL,
ALTER COLUMN "secretToken" DROP NOT NULL;
