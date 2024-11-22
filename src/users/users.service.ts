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
      throw new NotFoundException('Usuario no encontrado');
    }

    // Generar token aleatorio
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hash = await bcrypt.hash(resetToken, 10);

    // Guardar token y fecha de expiración
    user.resetPasswordToken = hash;
    user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hora
    await this.usersRepository.save(user);

    // Enviar email
    const resetUrl = `https://tu-frontend.com/reset-password?token=${resetToken}&email=${email}`;
    
    await this.transporter.sendMail({
      to: email,
      subject: 'Recuperación de Contraseña',
      html: `
        <p>Has solicitado restablecer tu contraseña.</p>
        <p>Haz clic en el siguiente enlace para continuar:</p>
        <a href="${resetUrl}">Restablecer Contraseña</a>
        <p>Este enlace expirará en 1 hora.</p>
        <p>Si no solicitaste esto, ignora este email.</p>
      `,
    });
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