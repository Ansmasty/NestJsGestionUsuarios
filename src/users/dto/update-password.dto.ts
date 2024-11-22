import { ApiProperty } from '@nestjs/swagger';

export class UpdatePasswordDto {
  @ApiProperty()
  email: string;

  @ApiProperty()
  currentPassword: string;

  @ApiProperty()
  newPassword: string;
}