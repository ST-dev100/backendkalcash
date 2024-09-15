// mailer.module.ts
import { Module } from '@nestjs/common';
import { MailerServiceService } from './mailer-service.service'; // Your mailer service

@Module({
  providers: [MailerServiceService],
  exports: [MailerServiceService], // Export the service so it can be used in other modules
})
export class MailerModule {}  
