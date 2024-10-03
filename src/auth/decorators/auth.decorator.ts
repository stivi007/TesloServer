
import { applyDecorators, UseGuards } from '@nestjs/common';
import { ValidRoles } from '../interfaces/valid-roles';
import { RoleProtected } from './role-protected.decorator';
import { AuthGuard } from '@nestjs/passport';
import { UseRoleGuard } from '../guards/use-role.guard';

export function Auth(...roles: ValidRoles[]) {
  return applyDecorators(

    RoleProtected(...roles),

    // SetMetadata('roles', roles),
    UseGuards(AuthGuard(), UseRoleGuard),
  );
}