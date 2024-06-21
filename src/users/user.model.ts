import { Column, Model, Table } from 'sequelize-typescript';

@Table
export class User extends Model<User> {
  @Column({
    primaryKey: true,
    autoIncrement: true,
  })
  id: number;

  @Column
  name: string;

  @Column({ unique: true })
  email: string;

  @Column
  password: string;

  @Column
  activationToken: string;

  @Column({ defaultValue: false })
  activated: boolean;

  @Column
  resetToken: string;

  @Column
  resetTokenExpiry: Date;
}
