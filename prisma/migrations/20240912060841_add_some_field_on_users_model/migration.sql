/*
  Warnings:

  - Added the required column `secretToken` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "User" ADD COLUMN     "activate" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "enable2FA" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "profileImage" TEXT,
ADD COLUMN     "secretToken" TEXT NOT NULL;
