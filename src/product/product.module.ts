import { MiddlewareConsumer, Module, NestModule, OnModuleInit } from '@nestjs/common';
import { ProductService } from './product.service';
import { ProductController } from './product.controller';
import { AuthModule } from 'src/auth/auth.module';
import { tenantModels } from 'src/tenant/providers/tenant-model.provider';
import { TenantsMiddleware } from 'src/tenant/middlewares/tenant.middleware';
import { TenantModule } from 'src/tenant/tenant.module';
import { ContextIdFactory } from '@nestjs/core';
import { AggregateByTenantContextIdStrategy } from 'src/tenant/strategies/tenant-context-id.strategy';

@Module({
  controllers: [ProductController],
  providers: [tenantModels.productModel, ProductService],
  imports:[AuthModule, TenantModule]
})
export class ProductModule implements NestModule, OnModuleInit {
  onModuleInit() {
    ContextIdFactory.apply(new AggregateByTenantContextIdStrategy());
  }
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TenantsMiddleware).forRoutes(ProductController);
  }
}
