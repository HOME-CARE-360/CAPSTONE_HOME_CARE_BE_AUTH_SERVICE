import { UnauthorizedException, UnprocessableEntityException } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';

export const InvalidOTPException = new RpcException(
    new UnprocessableEntityException([
        { message: 'Invalid OTP code', path: 'code' },
    ]),
);

export const OTPExpiredException = new RpcException(
    new UnprocessableEntityException([
        { message: 'OTP code has expired', path: 'code' },
    ]),
);

export const FailedToSendOTPException = new RpcException(
    new UnprocessableEntityException([
        { message: 'Failed to send OTP code', path: 'code' },
    ]),
);

export const RefreshTokenRevokedException = new RpcException(
    new UnauthorizedException({
        message: 'Refresh token has been revoked',
        path: 'refreshToken',
    }),
);

export const ServiceProviderAlreadyExistsException = new RpcException(
    new UnprocessableEntityException([
        { message: 'Service provider with this Tax ID or Name already exists', path: ['taxId', 'name'] },
    ]),
);

export const InvalidPasswordException = new RpcException(
    new UnprocessableEntityException([
        { message: 'Invalid password', path: 'password' },
    ]),
);

export const RefreshTokenAlreadyUsedException = new RpcException(
    new UnauthorizedException('Refresh token has already been used'),
);

export const GoogleUserInfoError = new RpcException(
    new Error('Failed to get user info from Google'),
);

export const InvalidTOTPException = new RpcException(
    new UnprocessableEntityException([
        { message: 'Invalid TOTP code', path: 'totpCode' },
    ]),
);

export const TOTPAlreadyEnabledException = new RpcException(
    new UnprocessableEntityException([
        { message: 'TOTP is already enabled for this account', path: 'totpCode' },
    ]),
);

export const TOTPNotEnabledException = new RpcException(
    new UnprocessableEntityException([
        { message: 'TOTP is not enabled for this account', path: 'totpCode' },
    ]),
);

export const InvalidTOTPAndCodeException = new RpcException(
    new UnprocessableEntityException([
        { message: 'Invalid TOTP code', path: 'totpCode' },
        { message: 'Invalid OTP code', path: 'code' },
    ]),
);

export const UnauthorizedExceptionRpc = new RpcException(
    new UnauthorizedException('Unauthorized access'),
);
