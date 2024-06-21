import {
  Injectable,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { User } from '../users/user.model';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as nodemailer from 'nodemailer';
import { Op } from 'sequelize';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User) private userModel: typeof User,
    private readonly configService: ConfigService,
  ) {}

  async register(name: string, email: string, password: string): Promise<void> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const activationToken = this.generateToken();

    const user = new this.userModel({
      name,
      email,
      password: hashedPassword,
      activationToken,
      activated: false,
    });

    await user.save();

    const activationLink = `${this.configService.get<string>('clientUrl')}/activate-account?token=${activationToken}`;
    await this.sendEmail(
      email,
      'Account Activation',
      `Click <a href="${activationLink}">here</a> to activate your account.`,
    );
  }

  async activateAccount(token: string): Promise<void> {
    const user = await this.userModel.findOne({
      where: { activationToken: token },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid or expired token.');
    }

    user.activationToken = null;
    user.activated = true;
    await user.save();
  }

  async login(email: string, password: string): Promise<string> {
    const user = await this.userModel.findOne({ where: { email } });

    if (
      !user ||
      !(await bcrypt.compare(password, user.password)) ||
      !user.activated
    ) {
      throw new UnauthorizedException('Invalid email or password.');
    }

    return jwt.sign(
      { userId: user.id },
      this.configService.get<string>('jwtSecret'),
      { expiresIn: '24h' },
    );
  }

  async getProfile(userId: number): Promise<User> {
    const user = await this.userModel.findByPk(userId, {
      attributes: {
        exclude: [
          'password',
          'activationToken',
          'resetToken',
          'resetTokenExpiry',
        ],
      },
    });

    if (!user) {
      throw new NotFoundException('User not found.');
    }

    return user;
  }

  async changePassword(
    userId: number,
    oldPassword: string,
    newPassword: string,
    confirmPassword: string,
  ): Promise<void> {
    if (newPassword !== confirmPassword) {
      throw new UnauthorizedException('New passwords do not match.');
    }

    const user = await this.userModel.findByPk(userId);

    if (!user || !(await bcrypt.compare(oldPassword, user.password))) {
      throw new UnauthorizedException('Old password is incorrect.');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
  }

  async forgotPassword(email: string): Promise<void> {
    const user = await this.userModel.findOne({ where: { email } });

    if (!user) {
      return;
    }

    const resetToken = this.generateToken();
    user.resetToken = resetToken;
    user.resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now
    await user.save();

    const resetLink = `${this.configService.get<string>('clientUrl')}/reset-password?token=${resetToken}`;
    await this.sendEmail(
      email,
      'Password Reset',
      `Click <a href="${resetLink}">here</a> to reset your password.`,
    );
  }

  async resetPassword(
    token: string,
    newPassword: string,
    confirmPassword: string,
  ): Promise<void> {
    if (newPassword !== confirmPassword) {
      throw new UnauthorizedException('New passwords do not match.');
    }

    const user = await this.userModel.findOne({
      where: { resetToken: token, resetTokenExpiry: { [Op.gt]: new Date() } },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid or expired token.');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();
  }

  private generateToken(length = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  private async sendEmail(
    to: string,
    subject: string,
    html: string,
  ): Promise<void> {
    const transporter = nodemailer.createTransport({
      host: this.configService.get<string>('smtpHost'),
      port: this.configService.get<number>('smtpPort'),
      auth: {
        user: this.configService.get<string>('smtpUser'),
        pass: this.configService.get<string>('smtpPass'),
      },
    });

    const mailOptions = {
      from: 'no-reply@example.com',
      to,
      subject,
      html,
    };

    await transporter.sendMail(mailOptions);
  }
}
