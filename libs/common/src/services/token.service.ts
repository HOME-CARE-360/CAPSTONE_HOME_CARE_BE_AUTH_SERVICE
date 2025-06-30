import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt'

import { v4 as uuid } from "uuid"
import { AccessTokenPayload, AccessTokenPayloadCreate, RefreshTokenPayload, RefreshTokenPayloadCreate } from '../types/jwt.type';
import { ConfigService } from '@nestjs/config';
@Injectable()
export class TokenService {
    constructor(private readonly jwtService: JwtService, private configService: ConfigService) { }
    signAccessToken(payload: AccessTokenPayloadCreate) {
        console.log(this.configService.get("ACCESS_TOKEN_SECRET"));
        return this.jwtService.sign({ ...payload, uuid: uuid() }, {


            secret: this.configService.get("ACCESS_TOKEN_SECRET"),
            expiresIn: this.configService.get("ACCESS_TOKEN_EXPIRES_IN"),
            algorithm: "HS256"

        })
    }
    signRefreshToken(payload: RefreshTokenPayloadCreate) {
        console.log(this.configService.get("REFRESH_TOKEN_SECRET"));
        return this.jwtService.sign({ ...payload, uuid: uuid() }, {
            secret: this.configService.get(""),
            expiresIn: this.configService.get("REFRESH_TOKEN_EXPIRES_IN"),
            algorithm: "HS256"

        })
    }
    verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
        console.log(this.configService.get("REFRESH_TOKEN_SECRET"));
        return this.jwtService.verifyAsync(token, {
            secret: this.configService.get("REFRESH_TOKEN_SECRET"),

        })
    }
    verifyAccessToken(token: string): Promise<AccessTokenPayload> {
        return this.jwtService.verifyAsync(token, {
            secret: this.configService.get("ACCESS_TOKEN_SECRET"),

        })
    }
}
