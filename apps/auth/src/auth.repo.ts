import { Injectable } from "@nestjs/common";

import { DeviceType, RefreshTokenType, VerificationCodeType } from "../../../libs/common/src/request-response-type/auth/auth.model";
import { PrismaService } from "libs/common/src/services/prisma.service";
import { UserType } from "libs/common/src/models/shared-user.model";
import { RoleType } from "libs/common/src/models/shared-role.model";
import { TypeOfVerificationCodeType } from "libs/common/src/constants/auth.constant";
import { WhereUniqueUserType } from "libs/common/src/repositories/shared-user.repo";
import { CreateServiceProviderType } from "libs/common/src/models/shared-provider.model";
import { VerificationStatus } from "@prisma/client";




@Injectable()
export class AuthReponsitory {
    constructor(private readonly prismaService: PrismaService) { }

    async createVerificationCode(payload: Pick<VerificationCodeType, 'email' | 'type' | 'code' | 'expiresAt'>): Promise<VerificationCodeType> {
        await this.prismaService.verificationCode.deleteMany({
            where: {
                email: payload.email,
                type: payload.type,
            }
        })
        return this.prismaService.verificationCode.create({
            data: {

                email: payload.email,
                type: payload.type,
                code: payload.code,
                expiresAt: payload.expiresAt

            },

        })

    }
    async findUniqueVerificationCode(uniqueValue:
        | { id: number }
        | {
            email_code_type: {
                email: string
                type: TypeOfVerificationCodeType,
                code: string
            }
        },): Promise<VerificationCodeType | null> {
        return await this.prismaService.verificationCode.findUnique({
            where: uniqueValue
        })
    }
    createRefreshToken(data: {
        token: string,
        userId: number, expiresAt: Date, deviceId: number
    }) {
        return this.prismaService.refreshToken.create({
            data

        })
    }
    createDevice(
        data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'> & Partial<Pick<DeviceType, 'lastActive' | 'isActive'>>,
    ) {
        return this.prismaService.device.create({
            data,
        })
    }




    updateDevice(deviceId: number, data: Partial<DeviceType>): Promise<DeviceType> {
        return this.prismaService.device.update({
            where: {
                id: deviceId,
            },
            data,
        })
    }
    deleteRefreshToken(uniqueObject: { token: string }): Promise<RefreshTokenType> {
        return this.prismaService.refreshToken.delete({
            where: uniqueObject
        })
    }
    deleteVerificationCode(
        uniqueValue:
            | { id: number }
            | {
                email_code_type: {
                    email: string
                    type: TypeOfVerificationCodeType,
                    code: string
                }
            },
    ): Promise<VerificationCodeType> {
        return this.prismaService.verificationCode.delete({
            where: uniqueValue
        })
    }
    async findUniqueUserIncludeRole(where: WhereUniqueUserType): Promise<(UserType & { roles: Pick<RoleType, "id" | "name">[] } & { serviceProvider: { id: number, verificationStatus: VerificationStatus } | null } & { staff: { providerId: number, id: number } | null } & { customerProfile: { id: number } | null }) | null> {

        const user = await this.prismaService.user.findFirst({
            where: {
                ...where,
                deletedAt: null,
            },
            include: {
                roles: true,
                serviceProvider: {
                    select: {
                        id: true,
                        verificationStatus: true
                    }
                },
                staff: {
                    select: {
                        providerId: true,
                        id: true
                    }
                }, customerProfile: {
                    select: {
                        id: true
                    }
                }
            },
        })

        return user as (UserType & { roles: Pick<RoleType, "id" | "name">[] } & { serviceProvider: { id: number, verificationStatus: VerificationStatus } | null } & { staff: { providerId: number, id: number } | null } & { customerProfile: { id: number } }) | null
    }
    async findUniqueRefreshTokenIncludeUserRole(where: {
        token: string
    }): Promise<(RefreshTokenType & { user: UserType & { roles: RoleType } }) | null> {

        const refreshToken = await this.prismaService.refreshToken.findUnique({
            where,
            include: {
                user: {
                    include: {
                        roles: true,
                    },
                },
            },
        })
        return refreshToken as (RefreshTokenType & { user: UserType & { roles: RoleType } }) | null
    }
    async findUniqueProviderIncludeNameAndTaxId(where: {
        name: string;
        taxId: string;
    }): Promise<boolean> {
        const [providerWithTaxId, userWithName] = await Promise.all([
            this.prismaService.serviceProvider.findFirst({
                where: { taxId: where.taxId }
            }),
            this.prismaService.user.findFirst({
                where: { name: where.name }
            })
        ]);

        if (providerWithTaxId || userWithName) {

            return true;
        }
        return false
    }
    async createServiceProvider(body: CreateServiceProviderType) {
        await this.prismaService.serviceProvider.create({
            data: { ...body }
        })

    }

}