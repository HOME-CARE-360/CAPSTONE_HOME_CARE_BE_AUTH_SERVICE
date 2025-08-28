import { UnprocessableEntityException } from "@nestjs/common";
import { RpcException } from "@nestjs/microservices";

export const UserNotFoundException = new RpcException(
    new UnprocessableEntityException([
        {
            message: 'User not found',
            path: 'code',
        },
    ]),
);

export const EmailAlreadyExistsException = new RpcException(
    new UnprocessableEntityException([
        { message: 'Email already exists', path: 'email' },
    ]),
);

export const EmailNotFoundException = new RpcException(
    new UnprocessableEntityException([
        { message: 'Email not found', path: 'email' },
    ]),
);
