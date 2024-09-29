import { Body, Controller, Post } from '@nestjs/common';
import { TenantService } from './tenant.service';
import { createTenantDto } from './dtos/createTenant.dto';
import { assignTenantUserDto } from './dtos/assignTenantUser.dto';

@Controller('tenant')
export class TenantController {
    
    constructor(private tenantService:TenantService){}

    @Post('create')
    signup(@Body() reqbody: createTenantDto) {
       return this.tenantService.createTenant(reqbody)
    }

    @Post('assign-tenant-user')
    assignTenantUser(@Body() reqbody: assignTenantUserDto) {
        return this.tenantService.assignTenantUser(reqbody)
    }
}
