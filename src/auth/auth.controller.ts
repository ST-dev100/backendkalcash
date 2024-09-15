import { Controller, Post, Body, Request, UseGuards, Get, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  
  @Get('google')
  @UseGuards(AuthGuard('google')) 
  async googleAuth(@Req() req) {       
    // No need to do anything here. This will redirect to Google OAuth page.
  }  
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))  // Handles Google OAuth callback
  async googleAuthRedirect(@Req() req,@Res() res) {
    // This is where you get the user's Google account data 
    const googleUser = req.user; 
    
    // Check if the user exists in the database
    const existingUser = await this.authService.findUserByEmail(googleUser.email);
    
    if (!existingUser) {
      // If user doesn't exist, register them
      const registeredUser = await this.authService.registerGoogleUser(googleUser);
      return this.authService.login(registeredUser,res);
    } 
 
    // If the user exists, log them in
    return this.authService.login(existingUser,res);         
  }   
  
  @UseGuards(AuthGuard('local')) // Use the Local Strategy guard
  @Post('login')
  async login(@Request() req,@Res() res) { 
    return this.authService.login(req.user,res); // req.user contains the validated user
  }


  @Post('user-register') 
  async register(@Body() registerDto: { email: string; password: string; role: string; fullName: string;}) {
    return this.authService.registerUser(registerDto.email, registerDto.password, registerDto.role,registerDto.fullName);
  }
  @Post('activate')
  async activateUser(@Body() activateDto: { email: string; secretToken: string }) {
    return this.authService.activateUser(activateDto.email, activateDto.secretToken);
  }
  // @Post('enable-2fa')
  // // @UseGuards(JwtAuthGuard)
  // async enable2FA(@Body() req) {
  //   const user = await this.authService.enable2FA();
  //   return { message: '2FA enabled. Please check your email for the secret.' };
  // }

  @Post('verify-2fa')
  @UseGuards(JwtAuthGuard)
  async verify2FA(@Request() req, @Body('token') token: string) {
    const user = req.user;
    const isVerified = await this.authService.verify2FA(user, token);
    return isVerified ? { message: '2FA verified' } : { message: 'Invalid 2FA token' };
  }
  // Forgot password route
  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }
    // Route for reset password
    @Post('reset-password')
    async resetPassword(
      @Body('token') token: string,
      @Body('newPassword') newPassword: string,
    ) {
      return this.authService.resetPassword(token, newPassword);
    }
           
}

