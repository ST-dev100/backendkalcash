import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UsersService {
  // private users = users;

  // async findByEmail(email: string) {
  //   return this.users.find(user => user.email === email);
  // }

  // async validateUser(email: string, password: string) {
  //   const user = await this.findByEmail(email);
  //   if (user && bcrypt.compareSync(password, user.password)) {
  //     return user;
  //   }
  //   return null;
  // }

  // async registerUser(email: string, password: string, role: string) {
  //   const hashedPassword = await bcrypt.hash(password, 10);
  //   const newUser = {
  //     id: this.users.length + 1,
  //     email,
  //     password: hashedPassword,
  //     role,
  //     is2FAEnabled: false,
  //     twoFactorSecret: null,
  //   };
  //   this.users.push(newUser);
  //   return newUser;
  // }
}
