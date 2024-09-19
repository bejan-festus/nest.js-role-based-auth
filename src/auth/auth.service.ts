import { Injectable, UnauthorizedException } from '@nestjs/common';
import { createUserDto } from 'src/users/dtos/createUser.dto';
import { UserService } from 'src/users/user.service';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { AuthToken } from './models/auth.model';
import { Model } from 'mongoose';
import { loginDto } from './dtos/login.dto';
import { refreshTokenDto } from './dtos/refreshToken.dto';


@Injectable()
export class AuthService {

    constructor(private userService: UserService, private configService: ConfigService, private jwtService: JwtService, @InjectModel(AuthToken.name) private AuthTokenModel:Model<AuthToken>) { }

    async signup(user: createUserDto): Promise<Record<string, string>> {

        const hashedPassword = await this.encryptPassword(user.password)

        user = {
            ...user,
            password: hashedPassword
        }

        const createdUser = await this.userService.createUser(user)

        const token = {
            access:this.generateAccessToken({ userId: createdUser._id.toString() }),
            refresh:this.generateRefreshToken({ userId: createdUser._id.toString() }),
            userId:createdUser._id
        }

        this.saveTokens(token)

        return {access:token.access}
    }

    async encryptPassword(password: string): Promise<string> {

        const rounds = 10

        const hash = await bcrypt.hash(password, rounds);

        return hash

    }

    async verifyPassword(password: string, hash:string) {

        const isMatch = await bcrypt.compare(password, hash); 

        return isMatch

    }

    generateAccessToken(payload: { userId: string }): string {
        return this.jwtService.sign(payload);
    }

    generateRefreshToken(payload: { userId: string }): string {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('jwt.jwtRefreshSecret'),
            expiresIn: this.configService.get<string>('jwt.jwtRefreshIn'),
        });
    }

    saveTokens(token:AuthToken){
        const createdToken = new this.AuthTokenModel(token)

        createdToken.save()
    }

    updateTokenByUserId(token:AuthToken){
        return this.AuthTokenModel.updateOne({userId:token.userId}, {$set:{access:token.access, refresh:token.refresh}}, {upsert:true})
    }

   async login(userCreds:loginDto){

     const user = await this.userService.getUserByEmail(userCreds.email)

     if(!user){
        throw new UnauthorizedException()
     }

    const isMatch =  await this.verifyPassword(userCreds.password, user.password)

    if(!isMatch){
        throw new UnauthorizedException()
    }

    const token:AuthToken = {
        userId:user._id,
        access:this.generateAccessToken({userId: user._id.toString()}),
        refresh:this.generateRefreshToken({userId: user._id.toString()})
    }    

    await this.updateTokenByUserId(token)

    return {access:token.access}
    
    }

    async refreshToken(accessTokenObj:refreshTokenDto){
        const tokenDoc:AuthToken = await this.findOneAccessToken(accessTokenObj.access)

        if(!tokenDoc){
            throw new UnauthorizedException()
        }

        const newToken:AuthToken = {
            userId:tokenDoc.userId,
            access:this.generateAccessToken({userId: tokenDoc.userId.toString()}),
            refresh:this.generateRefreshToken({userId: tokenDoc.userId.toString()})
        }    
    
        await this.updateTokenByUserId(newToken)

        return {access:newToken.access}
    }

    findOneAccessToken(token:string){
        return this.AuthTokenModel.findOne({access:token})
    }


}
