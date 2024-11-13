import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { Request } from "express";
import { ConfigService } from "@nestjs/config";
import { AuthService } from "../auth.service";
import { TenantService } from "src/tenant/tenant.service";
import { decrypt } from "src/utils/decrypt.util";

@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(private jwtService: JwtService, private authService: AuthService, private tenantService: TenantService, private configService: ConfigService) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const reqToken = this.extractTokenFromHeader(request);
    if (!reqToken) {
      throw new UnauthorizedException();
    }

    const tokenInDb = await this.authService.findOneAccessToken(reqToken)

    if (!tokenInDb) {
      throw new UnauthorizedException();
    }        

    const isUserAssigned = await this.tenantService.isUserAssignedToTenant({tenantId: request.tenantId, userId: tokenInDb.userId.toString()})    

    if(!isUserAssigned){
      throw new UnauthorizedException();
    }

    const [iv, encrypted] = request.jwtAccessSecret.split('.')    

    const secret = decrypt(encrypted, iv, this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))

    try {
      const payload: { userId: string, iat: number, exp: number } = await this.jwtService.verifyAsync(reqToken, {
        secret: secret,
      });

      request['userId'] = payload.userId;

    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
