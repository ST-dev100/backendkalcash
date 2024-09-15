// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { PrismaModule } from '../prisma/prisma.module'; // Import PrismaModule
import { MailerModule } from 'src/mailer/mailer.module';

@Module({
  imports: [PrismaModule, JwtModule.register({
    secret: 'your_jwt_secret', // Use a real secret in production
    signOptions: { expiresIn: '1h' },
  }),MailerModule], 
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
