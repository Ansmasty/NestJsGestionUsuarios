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
    console.log('Iniciando configuración de email en ambiente:', process.env.NODE_ENV);
    
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.warn('Variables de email no configuradas:', {
        EMAIL_USER_EXISTS: !!process.env.EMAIL_USER,
        EMAIL_PASSWORD_EXISTS: !!process.env.EMAIL_PASSWORD
      });
      return;
    }

    try {
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
        },
        debug: true,
        logger: true
      });

      // Verificar configuración inmediatamente
      this.verifyConnection();
    } catch (error) {
      console.error('Error al configurar transporter:', error);
    }
  }

  private async verifyConnection() {
    try {
      const verification = await this.transporter.verify();
      console.log('Configuración SMTP verificada:', verification);
    } catch (error) {
      console.error('Error en verificación SMTP:', error);
      console.error('Detalles de configuración:', {
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
          user: process.env.EMAIL_USER ? 'configurado' : 'no configurado',
          pass: process.env.EMAIL_PASSWORD ? 'configurado' : 'no configurado'
        }
      });
    }
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
    try {
      const user = await this.usersRepository.findOne({ where: { email } });
      if (!user) {
        return;
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      const hashedToken = await bcrypt.hash(resetToken, 10);

      user.resetPasswordToken = hashedToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000);
      await this.usersRepository.save(user);

      if (!this.transporter) {
        console.log('Modo desarrollo - Token:', resetToken);
        return;
      }

      const mailOptions = {
        from: {
          name: 'Sistema de Recuperación',
          address: process.env.EMAIL_USER
        },
        to: user.email,
        subject: 'Recuperación de Contraseña',
        html: `
          <h3>Recuperación de Contraseña</h3>
          <p>Has solicitado restablecer tu contraseña.</p>
          <p>Tu token de recuperación es: <strong>${resetToken}</strong></p>
          <p>Este token expirará en 1 hora.</p>
        `
      };

      try {
        const info = await this.transporter.sendMail(mailOptions);
        console.log('Email enviado:', info.response);
      } catch (emailError) {
        console.error('Error al enviar email:', emailError);
        console.log('Token de respaldo:', resetToken);
      }
    } catch (error) {
      console.error('Error en requestPasswordReset:', error);
      throw new UnauthorizedException('Error al procesar la solicitud');
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

    // Comparar el token recibido con el hash almacenado
    const isValidToken = await bcrypt.compare(token, user.resetPasswordToken);
    if (!isValidToken) {
      throw new UnauthorizedException('Token inválido');
    }

    // Actualizar contraseña
    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    await this.usersRepository.save(user);
  }
}