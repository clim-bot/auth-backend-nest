import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(
    @Body() body: { name: string; email: string; password: string },
  ): Promise<void> {
    const { name, email, password } = body;
    return this.authService.register(name, email, password);
  }

  @Post('activate-account')
  async activateAccount(@Body() body: { token: string }): Promise<void> {
    const { token } = body;
    return this.authService.activateAccount(token);
  }

  @Post('login')
  async login(
    @Body() body: { email: string; password: string },
  ): Promise<{ token: string }> {
    const { email, password } = body;
    const token = await this.authService.login(email, password);
    return { token };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req): Promise<any> {
    return this.authService.getProfile(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  async changePassword(
    @Request() req,
    @Body()
    body: { oldPassword: string; newPassword: string; confirmPassword: string },
  ): Promise<void> {
    const { oldPassword, newPassword, confirmPassword } = body;
    return this.authService.changePassword(
      req.user.userId,
      oldPassword,
      newPassword,
      confirmPassword,
    );
  }

  @Post('forgot-password')
  async forgotPassword(@Body() body: { email: string }): Promise<void> {
    const { email } = body;
    return this.authService.forgotPassword(email);
  }

  @Post('reset-password')
  async resetPassword(
    @Body()
    body: {
      token: string;
      newPassword: string;
      confirmPassword: string;
    },
  ): Promise<void> {
    const { token, newPassword, confirmPassword } = body;
    return this.authService.resetPassword(token, newPassword, confirmPassword);
  }
}
