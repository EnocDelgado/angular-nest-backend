import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';


import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot(), //access to ours env
    
    MongooseModule.forRoot(process.env.MONGO_URI, {
      dbName: process.env.MONGODB_NAME
    }),
    
    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
