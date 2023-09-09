package tacos.web.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.PagedModel;
import org.springframework.hateoas.server.RepresentationModelProcessor;
import org.springframework.hateoas.server.mvc.WebMvcLinkBuilder;

import tacos.Taco;

@Configuration
public class SpringDataRestConfiguration {

  @Bean
  public RepresentationModelProcessor<PagedModel<EntityModel<Taco>>>
    tacoProcessor() {
	  return new RepresentationModelProcessor<PagedModel<EntityModel<Taco>>>() {
		  @Override
		  public PagedModel<EntityModel<Taco>> process(
				  PagedModel<EntityModel<Taco>> resource) {
			  
			  // Using WebMvcLinkBuilder to build the link
			  resource.add(
					  WebMvcLinkBuilder.linkTo(
							  WebMvcLinkBuilder.methodOn(RecentTacosController.class)
							  .recentTacos())
					  .withRel("recents"));
			  return resource;
		  }
	  };   
  }
  
}




//package tacos.web.api;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.hateoas.EntityLinks;
//import org.springframework.hateoas.EntityModel;
//import org.springframework.hateoas.PagedModel;
//import org.springframework.hateoas.server.RepresentationModelProcessor;
//
//import tacos.Taco;
//
//@Configuration
//public class SpringDataRestConfiguration {
//
//  @Bean
//  public RepresentationModelProcessor<PagedModel<EntityModel<Taco>>>
//    tacoProcessor(EntityLinks links) {
//	  return new RepresentationModelProcessor<PagedModel<EntityModel<Taco>>>() {
//		  @Override
//		  public PagedModel<EntityModel<Taco>> process(
//				  PagedModel<EntityModel<Taco>> resource) {
//			  resource.add(
//					  links.linkFor(Taco.class)
//					  .slash("recent")
//					  .withRel("recents"));
//			  return resource;
//		  }
//	  };   
//  }
//  
//}
//
//
//
//
////package tacos.web.api;
////
////import org.springframework.context.annotation.Bean;
////import org.springframework.context.annotation.Configuration;
////import org.springframework.hateoas.EntityLinks;
////import org.springframework.hateoas.PagedResources;
////import org.springframework.hateoas.Resource;
////import org.springframework.hateoas.ResourceProcessor;
////
////import tacos.Taco;
////
////@Configuration
////public class SpringDataRestConfiguration {
////
////  @Bean
////  public ResourceProcessor<PagedResources<Resource<Taco>>>
////    tacoProcessor(EntityLinks links) {
////
////    return new ResourceProcessor<PagedResources<Resource<Taco>>>() {
////      @Override
////      public PagedResources<Resource<Taco>> process(
////                          PagedResources<Resource<Taco>> resource) {
////        resource.add(
////            links.linkFor(Taco.class)
////                 .slash("recent")
////                 .withRel("recents"));
////        return resource;
////      }
////    };
////  }
////  
////}
