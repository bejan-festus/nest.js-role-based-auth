import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ProductService } from './product.service';
import { ProductController } from './product.controller';
import { AuthModule } from 'src/auth/auth.module';
import { tenantModels } from 'src/tenant/providers/tenant-model.provider';
import { TenantsMiddleware } from 'src/middlewares/tenant.middleware';
import { TenantModule } from 'src/tenant/tenant.module';

@Module({
  controllers: [ProductController],
  providers: [tenantModels.productModel, ProductService],
  imports:[AuthModule, TenantModule]
})
export class ProductModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TenantsMiddleware).forRoutes(ProductController);
  }
}
