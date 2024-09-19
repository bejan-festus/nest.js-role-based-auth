import { Injectable } from '@nestjs/common';
import { User } from './user.model';
import mongoose, { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { createUserDto } from './dtos/createUser.dto';

@Injectable()
export class UserService {
    constructor(@InjectModel(User.name) private userModel:Model<User>){}


    createUser(user:createUserDto):Promise<User & {_id:mongoose.Types.ObjectId}>{
        const createdUser =  new this.userModel(user)
        return createdUser.save()
    }

    getUserByEmail(email:string):Promise<{password:string, _id:mongoose.Types.ObjectId}>{
        return this.userModel.findOne({email:email}, {password:1})
    }

   async getAllUsers():Promise<Omit<User, 'password' >[]>{
        return await this.userModel.find({},{firstName:1, lastName:1, email:1, _id:false})
    }


}
