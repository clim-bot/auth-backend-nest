import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SequelizeModule } from '@nestjs/sequelize';
import { AppConfigModule } from './config/config.module';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './auth/auth.module';
import { User } from './users/user.model';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    SequelizeModule.forRoot({
      dialect: 'sqlite',
      storage: process.env.SQLITE_STORAGE || 'database.sqlite',
      autoLoadModels: true,
      synchronize: true,
      models: [User],
    }),
    AppConfigModule,
    DatabaseModule,
    AuthModule,
  ],
})
export class AppModule {}
