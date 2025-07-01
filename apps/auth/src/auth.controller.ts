
import { Body, Controller, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';

import { ZodSerializerDto } from 'nestjs-zod';
import { GetAuthorizationUrlResDTO, LoginBodyDTO, RegisterResDTO, RefreshTokenResDTO, } from 'libs/common/src/request-response-type/auth/auth.dto';

import { GoogleService } from './google.service';



import { IsPublic } from 'libs/common/src/decorator/auth.decorator';
import { MessageResDTO } from 'libs/common/src/dtos/response.dto';
import { ConfigService } from '@nestjs/config';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { ForgotPasswordBodyType, LogoutBodyType, RefreshTokenBodyType, RegisterBodyType, RegisterProviderBodyType, SendOTPBodyType } from 'libs/common/src/request-response-type/auth/auth.model';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService, private readonly googleService: GoogleService, private configService: ConfigService) { }
  //done
  @MessagePattern({ cmd: 'register' })
  @IsPublic()
  @ZodSerializerDto(RegisterResDTO)
  async register(@Payload() body: RegisterBodyType) {
    return await this.authService.register(body)

  }
  //done
  @MessagePattern({ cmd: 'otp' })
  @IsPublic()
  async sendOTP(@Payload() body: SendOTPBodyType) {
    return await this.authService.sendOTP(body)
  }
  @MessagePattern({ cmd: 'login' })
  @IsPublic()
  login(@Payload() body: LoginBodyDTO & { ip: string, userAgent: string }) {
    return this.authService.login({
      ...body
    })


  }

  @MessagePattern({ cmd: 'refresh-token' })
  @IsPublic()
  @HttpCode(HttpStatus.OK)
  @ZodSerializerDto(RefreshTokenResDTO)
  refreshToken(@Payload() { ip, userAgent, refreshToken }: RefreshTokenBodyType & {
    ip: string, userAgent: string
  }
  ) {
    console.log(ip, userAgent, refreshToken);

    return this.authService.refreshToken({
      refreshToken, ip, userAgent
    })


  }
  //done
  @MessagePattern({ cmd: 'logout' })
  @ZodSerializerDto(MessageResDTO)
  logout(@Payload() body: LogoutBodyType) {
    console.log(body);
    return this.authService.logout(body.refreshToken)
  }
  //done
  @MessagePattern({ cmd: 'forgot-password' })
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  forgotPassword(@Body() body: ForgotPasswordBodyType) {
    return this.authService.forgotPassword(body)
  }
  //done
  @MessagePattern({ cmd: 'google-link' })
  @IsPublic()
  @ZodSerializerDto(GetAuthorizationUrlResDTO)
  getAuthorizationUrl(@Payload() { ip, userAgent }: { ip: string, userAgent: string }) {
    return this.googleService.getAuthorizationUrl({
      userAgent,
      ip,
    })
  }
  //done
  @MessagePattern({ cmd: 'google/callback' })
  @IsPublic()
  async googleCallback(@Payload() { code, state }: { code: string, state: string }) {
    const data = await this.googleService.googleCallback({
      code,
      state,
    })
    return data
  }
  //done
  @MessagePattern({ cmd: 'register-provider' })
  @IsPublic()
  @ZodSerializerDto(MessageResDTO)
  async registerProvider(@Payload() body: RegisterProviderBodyType) {
    console.log("vo r");

    return await this.authService.registerProvider(body)
  }

}

