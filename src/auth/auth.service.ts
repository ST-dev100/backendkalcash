import { Injectable, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as speakeasy from 'speakeasy';
import { Response } from 'express'; // Import Response from expres
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { MailerServiceService } from 'src/mailer/mailer-service.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService, // Inject PrismaService
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerServiceService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    // Find the user by email
    const user = await this.prisma.user.findUnique({ where: { email } });

    // Check if user exists and password is correct
    if (user && (await bcrypt.compare(password, user.password))) {
      // Check if the user is activated
      if (!user.activate) {
        return { message: 'User not verfyied' }; // Return null if the user is not activated
      }
      return user; // Return the user if password matches and the user is activated
    }

    return null; // Return null if no user is found or password is incorrect
  }

  async login(user: any,res:Response) {
    const payload = { email: user.email, sub: user.id }; 
    // console.log("inside login = ",user)
    // console.log("user activate is = ",user.user.activate) 
    let activated = user.activate || user.user.activate
    if (!activated) {  
      return { message: 'User is not activated' }; // Return message if the user is not activated
    } 
    // Remove password field from user data
  const { password, ...userWithoutPassword } = user;
    // Generate the JWT token
  const token = this.jwtService.sign(payload, {
    secret: 'your_jwt_secret', // Replace with your secret
  });

  // Set JWT token as a cookie
  res.cookie('access_token', token, {
    httpOnly: true, // Make cookie HTTP only for security
    secure: process.env.NODE_ENV === 'production', // Only use secure cookies in production
    sameSite: 'strict', // Prevent CSRF
    maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week expiration
  });

  // Set the user (without password) as a cookie
  res.cookie('user', userWithoutPassword, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week expiration
  });

  return res.json({ 
    message: 'Login successful',
    user: user, // Include access token in the response body
  });
  }

  async registerUser(
    email: string,
    password: string,
    role: string,
    fullName: string,
  ) {
    const userExists = await this.prisma.user.findUnique({
      where: { email },
    });

    if (userExists) {
      return { message: 'User already exists' };
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const secret = speakeasy.generateSecret({ length: 20 });
    const token = speakeasy.totp({
      secret: secret.base32,
      encoding: 'base32',
    });

    const newUser = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        role,
        fullName, // Add fullName here
        enable2FA: false,
        secretToken: secret.base32,
      },
    });
    await this.mailerService.sendEmail(newUser.email,`Enable Two-Factor Authentication`,`Your 2FA secret is ${token}`);
    return {
      message:
        'The verfication code has been sent to your email account successfully',
    };
  }

  //forgot Password

  async forgotPassword(email: string) { 
    // Find the user by email
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new BadRequestException('No user found with that email');
    }
    if (!user.password) {
      throw new BadRequestException('No password found with that email');
    }
    // Create a reset token that expires in 1 hour
    const resetToken = this.jwtService.sign(
      { id: user.id },
      { secret: 'simon', expiresIn: '1h' },
    );

    // Generate the reset URL
    const resetURL = `http://localhost:3000/reset-password/${resetToken}`;

    // Send reset email
    await this.mailerService.sendEmail(user.email,'Password Reset',`Please use the following link to reset your password: ${resetURL}`);

    return { message: 'Password reset link sent to your email address' };
  }
  //reset the password
  async resetPassword(token: string, newPassword: string) {
    try {
      // Verify token
      const decoded = this.jwtService.verify(token, { secret: 'simon' });
      console.log(decoded);
      // Check if decoded contains id
      if (typeof decoded === 'object' && 'id' in decoded) {
        const userId = decoded.id;

        // Find user by id
        const user = await this.prisma.user.findUnique({
          where: { id: userId },
        });
        if (!user) {
          throw new BadRequestException(
            'Invalid token or user no longer exists',
          );
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update user's password
        await this.prisma.user.update({
          where: { id: userId },
          data: { password: hashedPassword },
        });

        return {
          message:
            'Password reset successful, you can now log in with your new password',
        };
      } else {
        throw new BadRequestException('Invalid token');
      }
    } catch (error) {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  // Register a user from Google OAuth data
  async registerGoogleUser(googleUser: any) {
    // Create a new user with data from Google OAuth
    const newUser = await this.prisma.user.create({
      data: {
        email: googleUser.email,
        password: null, // No password for OAuth users
        role: 'user', // Assign default role
        fullName: `${googleUser.firstName} ${googleUser.lastName}`, // Construct full name
        profileImage: googleUser.picture, // Store user's Google profile picture
        activate:true, 
        enable2FA: false, // Disable 2FA by default
        secretToken: null, // No 2FA secret initially,
        googleId: googleUser.profile.id,
      },
    });

    return {
      message: 'Google user registered successfully',
      user: newUser,
    };
  }

  async activateUser(email: string, secretToken: string): Promise<any> {
    const user = await this.prisma.user.findUnique({ where: { email } });

    const isValid = speakeasy.totp.verify({
      secret: user.secretToken,
      encoding: 'base32',
      token: secretToken,
      window: 20, // Adjust time window to allow for time drift
    });
    console.log(isValid);
    if (isValid) {
      await this.prisma.user.update({
        where: { email },
        data: { activate: true, secretToken: null },
      });
      return { success: true, message: 'User activated successfully' }; // Send success response
    } else {
      return { success: false, message: 'Invalid activation token' }; // Send failure response
    }
  } 

  async verify2FA(user, token) {
    return speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 1,
    });
  }
  
  // This method finds the user by their email
  async findUserByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email }, // Prisma query to find the user by email
    });
  }
}
