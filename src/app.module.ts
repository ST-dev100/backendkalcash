import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { AuthService } from './auth/auth.service';
import { AuthController } from './auth/auth.controller';
import { AuthModule } from './auth/auth.module';
import { JwtModule } from '@nestjs/jwt';
import { GoogleStrategy } from './auth/google.strategy';
import { LocalStrategy } from './auth/local.strategy';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { MailerServiceService } from './mailer/mailer-service.service';
import { MailerModule } from './mailer/mailer.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes config globally available
    }),
    UsersModule,
    AuthModule,
    JwtModule,
    PrismaModule,
    MailerModule
  ],
  controllers: [AppController, AuthController],
  providers: [
    AppService,
    AuthService,
    GoogleStrategy,
    LocalStrategy,
    MailerServiceService,
  ],
})
export class AppModule {}
