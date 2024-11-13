import {
    Injectable,
    NestMiddleware,
    BadRequestException,
    NotFoundException,
  } from '@nestjs/common';
  import { Request, Response, NextFunction } from 'express';
import { TenantService } from 'src/tenant/tenant.service';
  
  @Injectable()
  export class TenantsMiddleware implements NestMiddleware {
    constructor(private tenantsService: TenantService) {}
  
    async use(req: Request, res: Response, next: NextFunction) {
      const tenantId = req.headers['x-tenant-id']?.toString();
      if (!tenantId) {
        throw new BadRequestException('X-TENANT-ID not provided');
      }
  
      const tenant = await this.tenantsService.getTenant(tenantId);
      if (!tenant) {
        throw new NotFoundException('Tenant does not exist');
      }
      req['tenantId'] = tenant._id.toString();
      req['jwtAccessSecret'] = tenant.jwtAccessSecret;
      next();
    }
  }