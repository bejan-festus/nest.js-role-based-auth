import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { RolesService } from './roles.service';
import { CreateRoleDto } from './dto/create-role.dto';
import { AuthenticationGuard } from 'src/auth/guards/authentication.guard';
import {Permissions } from 'src/auth/decorators/permission.decorator'
import { Resource } from './enums/resource.enum';
import { Action } from './enums/action.enum';
import { AuthorizationGuard } from 'src/auth/guards/authorization.guard';

@Controller('roles')
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Permissions([{ resource: Resource.roles, actions: [Action.read] }])
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Post('create-role')
  create(@Body() createRoleDto: CreateRoleDto) {
    return this.rolesService.create(createRoleDto);
  }


}
