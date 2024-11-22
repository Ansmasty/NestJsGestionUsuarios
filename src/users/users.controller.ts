import { Controller, Post, Body, Put, UnauthorizedException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'The user has been successfully created.' })
  @ApiResponse({ status: 400, description: 'Bad Request.' })
  @Post('register')
  async register(@Body() createUserDto: CreateUserDto) {
    return this.usersService.register(createUserDto.username, createUserDto.email, createUserDto.password);
  }

  @ApiOperation({ summary: 'Update user password' })
  @ApiResponse({ status: 200, description: 'Password updated successfully.' })
  @ApiResponse({ status: 401, description: 'Current password is incorrect.' })
  @ApiResponse({ status: 404, description: 'User not found.' })
  @Put('update-password')
  async updatePassword(@Body() updatePasswordDto: UpdatePasswordDto) {
    return this.usersService.updatePassword(
      updatePasswordDto.email,
      updatePasswordDto.currentPassword,
      updatePasswordDto.newPassword
    );
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body('email') email: string) {
    await this.usersService.requestPasswordReset(email);
    return { message: 'Si el email existe, recibirás instrucciones para restablecer tu contraseña' };
  }

  @Post('reset-password')
  async resetPassword(
    @Body('token') token: string,
    @Body('email') email: string,
    @Body('newPassword') newPassword: string,
  ) {
    await this.usersService.resetPassword(token, email, newPassword);
    return { message: 'Contraseña actualizada exitosamente' };
  }
}