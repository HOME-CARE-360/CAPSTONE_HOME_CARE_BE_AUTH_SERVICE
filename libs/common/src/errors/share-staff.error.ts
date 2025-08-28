import { NotFoundException } from "@nestjs/common";

export const StaffNotFoundOrNotBelongToProviderException = new NotFoundException([
    {
        message: 'Staff not found or does not belong to this provider',
        path: ['staffId'],
    },
]);
