import { BadRequestException } from "@nestjs/common";

export function InvalidCategoryIdException(invalidIds: number[]) {
    return new BadRequestException([
        {
            message: `Invalid category ID(s): ${invalidIds.join(", ")}`,
            path: ['categoryRequirements'],
            meta: { invalidIds },
        },
    ]);
}
