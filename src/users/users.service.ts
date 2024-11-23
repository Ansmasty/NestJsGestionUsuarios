import { Injectable, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import sgMail from '@sendgrid/mail';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {
    console.log('Iniciando servicio con variables de entorno:', {
      SENDGRID_KEY_EXISTS: !!process.env.SENDGRID_API_KEY,
      NODE_ENV: process.env.NODE_ENV
    });

    if (process.env.SENDGRID_API_KEY) {
      sgMail.setApiKey(process.env.SENDGRID_API_KEY);
      // Verificar configuración
      this.verifyConfig();
    }
  }

  private async verifyConfig() {
    try {
      const msg = {
        to: 'test@example.com',
        from: 'didierguzman333@gmail.com',
        subject: 'Test',
        text: 'Test'
      };
      await sgMail.send(msg);
      console.log('SendGrid configurado correctamente');
    } catch (error) {
      console.error('Error en configuración SendGrid:', error?.response?.body || error);
    }
  }

  async findByUsernameOrEmail(usernameOrEmail: string): Promise<User | undefined> {
    return this.usersRepository.findOne({
      where: [
        { username: usernameOrEmail },
        { email: usernameOrEmail },
      ],
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

      if (!process.env.SENDGRID_API_KEY) {
        console.log('SendGrid no configurado - Token:', resetToken);
        return;
      }

      const msg = {
        to: user.email,
        from: {
          email: 'didierguzman333@gmail.com', // Email verificado en SendGrid
          name: 'Sistema de Recuperación'
        },
        subject: 'Recuperación de Contraseña',
        html: `
          <div style="background-color: #f6f6f6; padding: 20px;">
            <h2 style="color: #333;">Recuperación de Contraseña</h2>
            <p>Has solicitado restablecer tu contraseña.</p>
            <p>Tu token de recuperación es:</p>
            <div style="background-color: #e9e9e9; padding: 10px; margin: 15px 0; font-family: monospace;">
              <strong>${resetToken}</strong>
            </div>
            <p>Este token expirará en 1 hora.</p>
            <p style="color: #666; font-size: 12px;">Si no solicitaste este cambio, puedes ignorar este mensaje.</p>
          </div>
        `,
        text: `Tu token de recuperación es: ${resetToken}. Este token expirará en 1 hora.`
      };

      try {
        const response = await sgMail.send(msg);
        console.log('Email enviado exitosamente:', response[0].statusCode);
      } catch (emailError) {
        console.error('Error al enviar email:', emailError?.response?.body || emailError);
        throw new Error('Error al enviar el email de recuperación');
      }
    } catch (error) {
      console.error('Error en requestPasswordReset:', error);
      throw new UnauthorizedException('Error al procesar la solicitud');
    }
  }

  async resetPassword(token: string, email: string, newPassword: string): Promise<void> {
    const user = await this.usersRepository.findOne({ where: { email } });

    if (!user || !user.resetPasswordToken) {
      throw new UnauthorizedException('Token inválido o expirado');
    }

    if (new Date() > user.resetPasswordExpires) {
      throw new UnauthorizedException('El token ha expirado');
    }

    const isValidToken = await bcrypt.compare(token, user.resetPasswordToken);
    if (!isValidToken) {
      throw new UnauthorizedException('Token inválido');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    await this.usersRepository.save(user);
  }
}