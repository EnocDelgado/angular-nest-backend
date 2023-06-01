import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcrypt from 'bcryptjs';

import { CreateUserDto, RegisterUserDto, LoginDto, UpdateAuthDto  } from './dto';

import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    // Interact with our DB
    @InjectModel( User.name ) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {
      // Encrypt password
      const { password, ...userData } = createUserDto;
      
      const newUser = new this.userModel({
        password: bcrypt.hashSync( password, 10 ),
        ...userData
      });

      // Save user
      await newUser.save();

      const { password:_, ...user } = newUser.toJSON();

      return user;

    } catch ( error ) {
      // Error
      if ( error.code === 11000 ) {
        throw new BadRequestException(`${ createUserDto.email } already exist!`)
      }
      throw new InternalServerErrorException('Something wrong happen!')
    }
  }

  async register( registerDto: RegisterUserDto): Promise<LoginResponse> {

    const user = await this.create( registerDto );

    return {
      user: user,
      token: this.getJwToken({ id: user._id })
    }
  }

  async login( loginDto: LoginDto ): Promise<LoginResponse> {
    /**
     * User { _id, name, email, roles }
     * Token -> ASDASD.ASDFASDF.ASDFGFG
     */
    const { email, password } = loginDto;

    // validate if exist email
    const user = await this.userModel.findOne({ email });
    if ( !user ) {
      throw new UnauthorizedException('No valid credentials - email ')
    }

    if ( !bcrypt.compareSync( password, user.password ) ) {
      throw new UnauthorizedException('Not valid credentials - email')
    }

    const { password:secret, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwToken({ id: user.id }),
    }

  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ) {
    const user = await this.userModel.findById( id );

    const { password, ...rest } = user.toJSON();

    return rest;
  }
  
  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwToken( payload: JwtPayload ) {
    const token = this.jwtService.sign( payload );

    return token;
  }
}
