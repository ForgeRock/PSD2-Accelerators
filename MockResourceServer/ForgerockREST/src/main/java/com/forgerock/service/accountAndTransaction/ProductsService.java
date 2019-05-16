package com.forgerock.service.accountAndTransaction;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.exceptions.ResourceNotFoundException;

import uk.org.openbanking.datamodel.account.Links;
import uk.org.openbanking.datamodel.account.Meta;
import uk.org.openbanking.datamodel.account.OBBCAData1;
import uk.org.openbanking.datamodel.account.OBExternalProductType2Code;
import uk.org.openbanking.datamodel.account.OBPCAData1;
import uk.org.openbanking.datamodel.account.OBProduct2;
import uk.org.openbanking.datamodel.account.OBReadProduct2;
import uk.org.openbanking.datamodel.account.OBReadProduct2Data;

public class ProductsService {
	
	private static final Logger log = LoggerFactory.getLogger(ProductsService.class);
	
	private OBReadProduct2 response;
	private OBReadProduct2Data data;
	private List<OBProduct2> productList;
	private static ProductsService stdregd = null;

	private ProductsService() {

		data = new OBReadProduct2Data();
		productList = getDefaultProductList();
		data.setProduct(productList);
		Links defaultLinks = LinksService.getInstance().getDefault();
		defaultLinks.setSelf("https://api.alphabank.com/open-banking/v3.1/aisp/products/");
		Meta defaultMeta = MetaService.getInstance().getDefault();
		
		response = new OBReadProduct2();
		response.setData(data);
		response.setLinks(defaultLinks);
		response.setMeta(defaultMeta);
	}

	public static ProductsService getInstance() {
		if (stdregd == null) {
			stdregd = new ProductsService();
			return stdregd;
		} else {
			return stdregd;
		}
	}
	
	public OBReadProduct2 getProducts() {
		data.setProduct(productList);
		response.setData(data);
		return response;
	}
	
	public OBReadProduct2 getProductByAccountId(String accountId) {
		String linkValue = String.format("https://api.alphabank.com/open-banking/v3.1/aisp/accounts/%s/product/", accountId);
		List<OBProduct2> newProductList = new ArrayList<OBProduct2>();
		for (OBProduct2 product : productList) {
			if (StringUtils.equals(product.getAccountId(), accountId)) {
				newProductList.add(product);
				break;
			}
		}
		if (newProductList.isEmpty()) {
			throw new ResourceNotFoundException(String.format("Product with account id %s not found!", accountId));
		}
		data.setProduct(newProductList);
		response.setData(data);
		response.getLinks().setSelf(linkValue);
		return response;
	}
	
	private List<OBProduct2> getDefaultProductList() {
		
		List<OBProduct2> productList = new ArrayList<>();
		
		/* First Product */
		OBProduct2 product1 = new OBProduct2();
		product1.setAccountId("22289");
		product1.setProductId("51B");
		product1.setProductType(OBExternalProductType2Code.PERSONALCURRENTACCOUNT);
		product1.setProductName("321 Product");
		product1.setPca(new OBPCAData1());
		productList.add(product1);
		
		/* Second Product */
		OBProduct2 product2 = new OBProduct2();
		product2.setAccountId("31820");
		product2.setProductId("001");
		product2.setProductType(OBExternalProductType2Code.BUSINESSCURRENTACCOUNT);
		product2.setProductName("123 Product");
		product2.setBca(new OBBCAData1());
		productList.add(product2);

		return productList;
	}

}
