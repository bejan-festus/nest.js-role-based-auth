import { Inject, Injectable } from '@nestjs/common';
import { addProductDto } from './dtos/addProduct.dto';
import { Model } from 'mongoose';
import { Product } from './product.model';

@Injectable()
export class ProductService {

    constructor(@Inject('PRODUCT_MODEL') private ProductModel: Model<Product>){}

    addProduct(reqBody:addProductDto){
      const createProduct = new this.ProductModel(reqBody)

     return createProduct.save()
    }
}
