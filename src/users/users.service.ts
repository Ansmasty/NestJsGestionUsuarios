import { Injectable, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import * as crypto from 'crypto';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  private transporter: nodemailer.Transporter;

  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {
    // Configura el transportador de email (usar variables de entorno en producción)
    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });
  }

  async register(username: string, email: string, password: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = this.usersRepository.create({ username, email, password: hashedPassword });
    return this.usersRepository.save(user);
  }

  async updatePassword(email: string, currentPassword: string, newPassword: string): Promise<User> {
    const user = await this.usersRepository.findOne({ where: { email } });
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('La contraseña actual es incorrecta');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    return this.usersRepository.save(user);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.usersRepository.findOne({ where: { email } });
    if (!user) {
      // Por seguridad, no revelamos si el email existe o no
      return;
    }

    try {
      // Generar token aleatorio
      const resetToken = crypto.randomBytes(32).toString('hex');
      const hash = await bcrypt.hash(resetToken, 10);

      // Guardar token y fecha de expiración
      user.resetPasswordToken = hash;
      user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hora
      await this.usersRepository.save(user);

      // En lugar de enviar email, solo guardamos el token
      // (para pruebas, devolvemos el token en la respuesta)
      console.log('Reset Token:', resetToken);
      
    } catch (error) {
      console.error('Error en requestPasswordReset:', error);
      throw new Error('Error al procesar la solicitud de reset');
    }
  }

  async resetPassword(token: string, email: string, newPassword: string): Promise<void> {
    const user = await this.usersRepository.findOne({ 
      where: { email }
    });

    if (!user || !user.resetPasswordToken) {
      throw new UnauthorizedException('Token inválido o expirado');
    }

    if (new Date() > user.resetPasswordExpires) {
      throw new UnauthorizedException('El token ha expirado');
    }

    // Verificar token
    const isValid = await bcrypt.compare(token, user.resetPasswordToken);
    if (!isValid) {
      throw new UnauthorizedException('Token inválido');
    }

    // Actualizar contraseña
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    await this.usersRepository.save(user);
  }
}