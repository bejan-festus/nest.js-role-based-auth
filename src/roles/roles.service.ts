import { Injectable } from '@nestjs/common';
import { CreateRoleDto } from './dto/create-role.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Role } from './roles.model';
import mongoose, { Model } from 'mongoose';

@Injectable()
export class RolesService {
  constructor(@InjectModel(Role.name) private roleSchema:Model<Role>){

  }
  create(createRoleDto: CreateRoleDto) {
    const createdRole = new this.roleSchema(createRoleDto)

    return createdRole.save()
  }


  findOne(id: string) : Promise<Role & {_id:mongoose.Types.ObjectId}>  {
   return this.roleSchema.findOne({_id:new mongoose.Types.ObjectId(id)})
  }


}
