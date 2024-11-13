import {
    HostComponentInfo,
    ContextId,
    ContextIdFactory,
    ContextIdStrategy,
  } from '@nestjs/core';
  
  const tenants = new Map<string, ContextId>();
  
  export class AggregateByTenantContextIdStrategy implements ContextIdStrategy {
    constructor(){}
    attach(contextId: ContextId, request) {
      const tenantId = request.tenantId;
      let tenantSubTreeId: ContextId;
  
      if (tenants.has(tenantId)) {
        tenantSubTreeId = tenants.get(tenantId);
      } else {
        tenantSubTreeId = ContextIdFactory.create();
        tenants.set(tenantId, tenantSubTreeId);
      }      
  
      return {
        resolve: (info: HostComponentInfo) => {  
          return info.isTreeDurable ? tenantSubTreeId : contextId;
        },
        payload: { tenantId: tenantId, jwtAccessSecret: request?.jwtAccessSecret },
      };
    }
    
  }