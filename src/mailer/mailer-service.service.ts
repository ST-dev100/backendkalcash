import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerServiceService {
    private transporter: nodemailer.Transporter;

    constructor() {
      // Set up the transporter with the Gmail service
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.USER_EMAIL, // Your email
          pass: process.env.USER_PASSWORD,   // Your email password or App password
        },
        tls: {
          rejectUnauthorized: false, // Disable certificate validation
        },
      });
    }
    
    // Send email method
    async sendEmail(to: string, subject: string, text: string) {
      await this.transporter.sendMail({
        from: '"Kal cash" <${process.env.USER_EMAIL}>', // sender address
        to,  // recipient
        subject,  // email subject
        text,  // email content
      });
    }
}
