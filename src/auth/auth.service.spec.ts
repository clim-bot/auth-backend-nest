import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { getModelToken } from '@nestjs/sequelize';
import { User } from '../users/user.model';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';

describe('AuthService', () => {
  let service: AuthService;
  let userModel: typeof User;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getModelToken(User),
          useValue: {
            create: jest.fn(),
            findOne: jest.fn(),
            findByPk: jest.fn(),
            save: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockImplementation((key: string) => {
              switch (key) {
                case 'JWT_SECRET':
                  return 'testsecret';
                case 'CLIENT_URL':
                  return 'http://localhost:3000';
                case 'SMTP_HOST':
                  return 'localhost';
                case 'SMTP_PORT':
                  return 1025;
                default:
                  return null;
              }
            }),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userModel = module.get<typeof User>(getModelToken(User));
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should hash the password and create a new user', async () => {
      const userDto = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123',
      };
      const hashedPassword = 'hashedPassword';
      const activationToken = 'activationToken';

      jest.spyOn(bcrypt, 'hash').mockResolvedValue(hashedPassword);
      jest
        .spyOn(service as any, 'generateToken')
        .mockReturnValue(activationToken);
      jest.spyOn(service as any, 'sendEmail').mockResolvedValue(undefined);

      await service.register(userDto.name, userDto.email, userDto.password);

      expect(bcrypt.hash).toHaveBeenCalledWith(userDto.password, 10);
      expect(userModel.create).toHaveBeenCalledWith({
        name: userDto.name,
        email: userDto.email,
        password: hashedPassword,
        activationToken,
        activated: false,
      });
      expect(service['sendEmail']).toHaveBeenCalled();
    });
  });

  describe('login', () => {
    it('should return a JWT token if credentials are valid', async () => {
      const userDto = { email: 'john@example.com', password: 'password123' };
      const user = {
        id: 1,
        email: 'john@example.com',
        password: 'hashedPassword',
        activated: true,
      };
      const jwtToken = 'jwtToken';

      jest.spyOn(userModel, 'findOne').mockResolvedValue(user as any);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);
      jest.spyOn(jwt, 'sign').mockReturnValue();

      const result = await service.login(userDto.email, userDto.password);

      expect(userModel.findOne).toHaveBeenCalledWith({
        where: { email: userDto.email },
      });
      expect(bcrypt.compare).toHaveBeenCalledWith(
        userDto.password,
        user.password,
      );
      expect(jwt.sign).toHaveBeenCalledWith({ userId: user.id }, 'testsecret', {
        expiresIn: '24h',
      });
      expect(result).toEqual(jwtToken);
    });

    it('should throw an UnauthorizedException if credentials are invalid', async () => {
      const userDto = { email: 'john@example.com', password: 'password123' };

      jest.spyOn(userModel, 'findOne').mockResolvedValue(null);

      await expect(
        service.login(userDto.email, userDto.password),
      ).rejects.toThrow('Unauthorized');
    });
  });
});
