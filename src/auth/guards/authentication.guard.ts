import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { Request } from "express";
import { ConfigService } from "@nestjs/config";
import { AuthService } from "../auth.service";
import { TenantService } from "src/tenant/tenant.service";
import { decrypt } from "src/utils/decrypt.util";

@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(private jwtService: JwtService, private authService:AuthService, private tenantService:TenantService, private configService:ConfigService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }

    const isTokenInDb = await this.authService.findOneAccessToken(token)

    if(!isTokenInDb){
      throw new UnauthorizedException();
    }

    const tenant = await this.tenantService.getTenant(request.tenantId)

    const iv = tenant.jwtAccessSecret.split('.')[0]
    const encrypted = tenant.jwtAccessSecret.split('.')[1]

    const secret = decrypt(encrypted, iv,this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))

    try {
      const payload:{userId:string, iat:number, exp:number} = await this.jwtService.verifyAsync(token, {
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
