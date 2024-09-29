import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { ProductService } from './product.service';
import { addProductDto } from './dtos/addProduct.dto';
import { AuthenticationGuard } from 'src/auth/guards/authentication.guard';

@Controller('product')
export class ProductController {
  constructor(private readonly productService: ProductService) {}

  @UseGuards(AuthenticationGuard)
  @Post('create')
  addProduct(@Body()reqBody:addProductDto){
   return this.productService.addProduct(reqBody)
  }

}
