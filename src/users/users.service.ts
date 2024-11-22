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
    // Inicializar transporter solo si las variables de entorno están presentes
    if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
        },
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
        return; // Silenciosamente retornamos si el usuario no existe
      }

      // Generar token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const hashedToken = await bcrypt.hash(resetToken, 10);

      // Actualizar usuario con el token
      user.resetPasswordToken = hashedToken;
      user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hora
      await this.usersRepository.save(user);

      // Si estamos en modo desarrollo o no hay configuración de email
      if (!this.transporter) {
        console.log('Modo desarrollo - Token generado:', resetToken);
        return;
      }

      // Enviar email
      try {
        await this.transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: 'Recuperación de Contraseña',
          html: `
            <h3>Recuperación de Contraseña</h3>
            <p>Has solicitado restablecer tu contraseña.</p>
            <p>Tu token de recuperación es: <strong>${resetToken}</strong></p>
            <p>Este token expirará en 1 hora.</p>
          `,
        });
      } catch (emailError) {
        console.error('Error al enviar email:', emailError);
        // En caso de error de email, aún mostramos el token en logs
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