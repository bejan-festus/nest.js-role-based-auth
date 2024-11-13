import { ConflictException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Tenant } from './models/tenant.model';
import mongoose, { Model } from 'mongoose';
import { createTenantDto } from './dtos/createTenant.dto';
import { assignTenantUserDto } from './dtos/assignTenantUser.dto';
import { UserService } from 'src/users/user.service';
import { TenantAssignedUser } from './models/tenantAssignedUsers.model';
import crypto from 'crypto';
import { encrypt } from 'src/utils/encrypt.util';
import { ConfigService } from '@nestjs/config';
import { decrypt } from 'src/utils/decrypt.util';


@Injectable()
export class TenantService {
    constructor(@InjectModel(Tenant.name) private tenantModel: Model<Tenant>,
        @InjectModel(TenantAssignedUser.name) private assignTenantUserModel: Model<TenantAssignedUser>,
        private userService: UserService, private configService: ConfigService) { }

   async createTenant(reqbody: createTenantDto): Promise<Tenant> {
        const isTenantExist = await this.tenantModel.findOne({ tenantName: { $regex: new RegExp(`^${reqbody.tenantName}$`, 'i') } })
        if(isTenantExist){
            throw new ConflictException('Tenant name already exist')
        }
        reqbody['jwtAccessSecret'] = this.generateSecret()
        reqbody['jwtRefreshSecret'] = this.generateSecret()
        reqbody['jwtResetPasswordSecret'] = this.generateSecret()
        const createTenant = new this.tenantModel(reqbody)
        return createTenant.save()
    }

    generateSecret() {
        const secret = crypto.randomBytes(64).toString('base64');
        const iv = crypto.randomBytes(16).toString('hex') // should be 16 byte long for aes256
        const encrypted = encrypt(secret, iv, this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))
        return iv + '.' + encrypted
    }

    decodeSecret(cipher: string) {
        const [iv, encrypted] = cipher.split('.')

        return decrypt(encrypted, iv, this.configService.get('jwt.tenantEncryptionAlgorithm'), this.configService.get('jwt.tenantEncryptionKey'))
    }

    async assignTenantUser(reqBody: assignTenantUserDto) {

        const user = await this.userService.getUserByEmail(reqBody.userEmail)

        const tenant: { _id: mongoose.Types.ObjectId } = await this.tenantModel.findOne({ tenantName: reqBody.tenantName }, { _id: 1 })

        const tenantUser: TenantAssignedUser = {
            userId: user._id,
            tenantId: tenant._id
        }

        const createTenantUser = new this.assignTenantUserModel(tenantUser)

        await createTenantUser.save()

        return { message: "User assigned successfully to tenant" }

    }

    isUserAssignedToTenant(reqObj:{tenantId:string, userId:string}):Promise<TenantAssignedUser>{
        return this.assignTenantUserModel.findOne({tenantId: new mongoose.Types.ObjectId(reqObj.tenantId) ,  userId: new mongoose.Types.ObjectId(reqObj.userId)  })
    }

    getTenant(tenantName: string): Promise<Tenant & {_id:mongoose.Types.ObjectId}> {
        return this.tenantModel.findOne({ tenantName: tenantName })
    }

    getTenantById(tenantId: mongoose.Types.ObjectId): Promise<Tenant> {
        return this.tenantModel.findOne({ _id: tenantId })
    }

    getUserAssignedTenant(userId: mongoose.Types.ObjectId): Promise<TenantAssignedUser> {
        return this.assignTenantUserModel.findOne({ userId: userId })
    }


}
