import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthService } from 'src/auth/auth.service';
import { Permission } from 'src/roles/dto/create-role.dto';
import { PERMISSIONS_KEY } from '../decorators/permission.decorator';
import { Action } from 'src/roles/enums/action.enum';

@Injectable()
export class AuthorizationGuard implements CanActivate {
    constructor(private reflector: Reflector, private authService: AuthService) { }
    async canActivate(context: ExecutionContext): Promise<boolean> {

        const request = context.switchToHttp().getRequest();

        if (!request.userId) {
            throw new UnauthorizedException('User not found');
        }

        const routePermissions: Permission[] = this.reflector.getAllAndOverride(
            PERMISSIONS_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (!routePermissions) {
            return true;
        }

        try {
            const userPermissions = await this.authService.getUserPermissions(
                request.userId,
            );

            for (const routePermission of routePermissions) {
                const userPermission = userPermissions.find(
                    (perm: Permission) => perm.resource === routePermission.resource,
                );

                if (!userPermission) throw new ForbiddenException();

                const allActionsAvailable = routePermission.actions.every(
                    (requiredAction: Action) => userPermission.actions.includes(requiredAction),
                );
                if (!allActionsAvailable) throw new ForbiddenException();
            }
        } catch (e) {
            throw new ForbiddenException();
        }
        return true;
    }
}